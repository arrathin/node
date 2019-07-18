// Copyright 2006-2008 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <iomanip>

#include "include/libplatform/libplatform.h"
#include "src/base/platform/platform.h"
#include "src/codegen/assembler-arch.h"
#include "src/codegen/source-position-table.h"
#include "src/flags/flags.h"
#include "src/sanitizer/msan.h"
#include "src/snapshot/embedded/embedded-file-writer.h"
#include "src/snapshot/natives.h"
#include "src/snapshot/partial-serializer.h"
#include "src/snapshot/snapshot.h"
#include "src/snapshot/startup-serializer.h"

#include "zos.h"

namespace {

class SnapshotFileWriter {
 public:
  void SetSnapshotFile(const char* snapshot_cpp_file) {
    snapshot_cpp_path_ = snapshot_cpp_file;
  }

  void SetStartupBlobFile(const char* snapshot_blob_file) {
    snapshot_blob_path_ = snapshot_blob_file;
  }

  void WriteSnapshot(v8::StartupData blob) const {
    // TODO(crbug/633159): if we crash before the files have been fully created,
    // we end up with a corrupted snapshot file. The build step would succeed,
    // but the build target is unusable. Ideally we would write out temporary
    // files and only move them to the final destination as last step.
    i::Vector<const i::byte> blob_vector(
        reinterpret_cast<const i::byte*>(blob.data), blob.raw_size);
    MaybeWriteSnapshotFile(blob_vector);
    MaybeWriteStartupBlob(blob_vector);
  }

 private:
  void MaybeWriteStartupBlob(const i::Vector<const i::byte>& blob) const {
    if (!snapshot_blob_path_) return;

    FILE* fp = GetFileDescriptorOrDie(snapshot_blob_path_);
    size_t written = fwrite(blob.begin(), 1, blob.length(), fp);
    fclose(fp);
    if (written != static_cast<size_t>(blob.length())) {
      i::PrintF("Writing snapshot file failed.. Aborting.\n");
      remove(snapshot_blob_path_);
      exit(1);
    }
  }

  void MaybeWriteSnapshotFile(const i::Vector<const i::byte>& blob) const {
    if (!snapshot_cpp_path_) return;

    FILE* fp = GetFileDescriptorOrDie(snapshot_cpp_path_);

    WriteSnapshotFilePrefix(fp);
    WriteSnapshotFileData(fp, blob);
    WriteSnapshotFileSuffix(fp);

    fclose(fp);
  }

  static void WriteSnapshotFilePrefix(FILE* fp) {
    fprintf(fp, "// Autogenerated snapshot file. Do not edit.\n\n");
    fprintf(fp, "#include \"src/init/v8.h\"\n");
    fprintf(fp, "#include \"src/base/platform/platform.h\"\n\n");
    fprintf(fp, "#include \"src/snapshot/snapshot.h\"\n\n");
    fprintf(fp, "namespace v8 {\n");
    fprintf(fp, "namespace internal {\n\n");
  }

  static void WriteSnapshotFileSuffix(FILE* fp) {
    fprintf(fp, "const v8::StartupData* Snapshot::DefaultSnapshotBlob() {\n");
    fprintf(fp, "  return &blob;\n");
    fprintf(fp, "}\n\n");
    fprintf(fp, "}  // namespace internal\n");
    fprintf(fp, "}  // namespace v8\n");
  }

  static void WriteSnapshotFileData(FILE* fp,
                                    const i::Vector<const i::byte>& blob) {
    fprintf(fp,
            "alignas(kPointerAlignment) static const byte blob_data[] = {\n");
    WriteBinaryContentsAsCArray(fp, blob);
    fprintf(fp, "};\n");
    fprintf(fp, "static const int blob_size = %d;\n", blob.length());
    fprintf(fp, "static const v8::StartupData blob =\n");
    fprintf(fp, "{ (const char*) blob_data, blob_size };\n");
  }

  static void WriteBinaryContentsAsCArray(
      FILE* fp, const i::Vector<const i::byte>& blob) {
    for (int i = 0; i < blob.length(); i++) {
      if ((i & 0x1F) == 0x1F) fprintf(fp, "\n");
      if (i > 0) fprintf(fp, ",");
      fprintf(fp, "%u", static_cast<unsigned char>(blob.at(i)));
    }
    fprintf(fp, "\n");
  }

  static FILE* GetFileDescriptorOrDie(const char* filename) {
    FILE* fp = v8::base::OS::FOpen(filename, "wb");
    if (fp == nullptr) {
      i::PrintF("Unable to open file \"%s\" for writing.\n", filename);
      exit(1);
    }
#ifdef V8_OS_ZOS
    __chgfdccsid(fileno(fp), 819);
#endif
    return fp;
  }

  const char* snapshot_cpp_path_ = nullptr;
  const char* snapshot_blob_path_ = nullptr;
};

char* GetExtraCode(char* filename, const char* description) {
  if (filename == nullptr || strlen(filename) == 0) return nullptr;
  ::printf("Loading script for %s: %s\n", description, filename);
  FILE* file = v8::base::OS::FOpen(filename, "rb");
  if (file == nullptr) {
    fprintf(stderr, "Failed to open '%s': errno %d\n", filename, errno);
    exit(1);
  }
  fseek(file, 0, SEEK_END);
  size_t size = ftell(file);
  rewind(file);
  char* chars = new char[size + 1];
  chars[size] = '\0';
  for (size_t i = 0; i < size;) {
    size_t read = fread(&chars[i], 1, size - i, file);
    if (ferror(file)) {
      fprintf(stderr, "Failed to read '%s': errno %d\n", filename, errno);
      exit(1);
    }
    i += read;
  }
  fclose(file);
  return chars;
}

v8::StartupData CreateSnapshotDataBlob(v8::Isolate* isolate,
                                       const char* embedded_source) {
  v8::base::ElapsedTimer timer;
  timer.Start();

  v8::StartupData result = i::CreateSnapshotDataBlobInternal(
      v8::SnapshotCreator::FunctionCodeHandling::kClear, embedded_source,
      isolate);

  if (i::FLAG_profile_deserialization) {
    i::PrintF("Creating snapshot took %0.3f ms\n",
              timer.Elapsed().InMillisecondsF());
  }

  timer.Stop();
  return result;
}

v8::StartupData WarmUpSnapshotDataBlob(v8::StartupData cold_snapshot_blob,
                                       const char* warmup_source) {
  v8::base::ElapsedTimer timer;
  timer.Start();

  v8::StartupData result =
      i::WarmUpSnapshotDataBlobInternal(cold_snapshot_blob, warmup_source);

  if (i::FLAG_profile_deserialization) {
    i::PrintF("Warming up snapshot took %0.3f ms\n",
              timer.Elapsed().InMillisecondsF());
  }

  timer.Stop();
  return result;
}

void WriteEmbeddedFile(i::EmbeddedFileWriter* writer) {
  i::EmbeddedData embedded_blob = i::EmbeddedData::FromBlob();
  writer->WriteEmbedded(&embedded_blob);
}

using CounterMap = std::map<std::string, int>;
CounterMap* counter_map_ = nullptr;

void MaybeSetCounterFunction(v8::Isolate* isolate) {
  // If --native-code-counters is on then we enable all counters to make
  // sure we generate code to increment them from the snapshot.
  //
  // Note: For the sake of the mksnapshot, the counter function must only
  // return distinct addresses for each counter s.t. the serializer can properly
  // distinguish between them. In theory it should be okay to just return an
  // incremented int value each time this function is called, but we play it
  // safe and return a real distinct memory location tied to every counter name.
  if (i::FLAG_native_code_counters) {
    counter_map_ = new CounterMap();
    isolate->SetCounterFunction([](const char* name) -> int* {
      auto map_entry = counter_map_->find(name);
      if (map_entry == counter_map_->end()) {
        counter_map_->emplace(name, 0);
      }
      return &counter_map_->at(name);
    });
  }
}

}  // namespace

int main(int argc, char** argv) {
  v8::base::EnsureConsoleOutput();

  // Make mksnapshot runs predictable to create reproducible snapshots.
  i::FLAG_predictable = true;

  // Print the usage if an error occurs when parsing the command line
  // flags or if the help flag is set.
  int result = i::FlagList::SetFlagsFromCommandLine(&argc, argv, true);
  if (result > 0 || (argc > 3) || i::FLAG_help) {
    ::printf("Usage: %s --startup_src=... --startup_blob=... [extras]\n",
             argv[0]);
    i::FlagList::PrintHelp();
    return !i::FLAG_help;
  }

  i::CpuFeatures::Probe(true);
  v8::V8::InitializeICUDefaultLocation(argv[0]);
  std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  v8::V8::Initialize();

  {
    SnapshotFileWriter snapshot_writer;
    snapshot_writer.SetSnapshotFile(i::FLAG_startup_src);
    snapshot_writer.SetStartupBlobFile(i::FLAG_startup_blob);

    i::EmbeddedFileWriter embedded_writer;
    embedded_writer.SetEmbeddedFile(i::FLAG_embedded_src);
    embedded_writer.SetEmbeddedVariant(i::FLAG_embedded_variant);
    embedded_writer.SetTargetArch(i::FLAG_target_arch);
    embedded_writer.SetTargetOs(i::FLAG_target_os);

    std::unique_ptr<char> embed_script(
        GetExtraCode(argc >= 2 ? argv[1] : nullptr, "embedding"));
    std::unique_ptr<char> warmup_script(
        GetExtraCode(argc >= 3 ? argv[2] : nullptr, "warm up"));

    i::DisableEmbeddedBlobRefcounting();
    v8::StartupData blob;
    {
      v8::Isolate* isolate = v8::Isolate::Allocate();

      MaybeSetCounterFunction(isolate);

      if (i::FLAG_embedded_builtins) {
        // Set code range such that relative jumps for builtins to
        // builtin calls in the snapshot are possible.
        i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
        size_t code_range_size_mb =
            i::kMaximalCodeRangeSize == 0
                ? i::kMaxPCRelativeCodeRangeInMB
                : std::min(i::kMaximalCodeRangeSize / i::MB,
                           i::kMaxPCRelativeCodeRangeInMB);
        v8::ResourceConstraints constraints;
        constraints.set_code_range_size_in_bytes(code_range_size_mb * i::MB);
        i_isolate->heap()->ConfigureHeap(constraints);
        // The isolate contains data from builtin compilation that needs
        // to be written out if builtins are embedded.
        i_isolate->RegisterEmbeddedFileWriter(&embedded_writer);
      }
      blob = CreateSnapshotDataBlob(isolate, embed_script.get());
      if (i::FLAG_embedded_builtins) {
        // At this point, the Isolate has been torn down but the embedded blob
        // is still alive (we called DisableEmbeddedBlobRefcounting above).
        // That's fine as far as the embedded file writer is concerned.
        WriteEmbeddedFile(&embedded_writer);
      }
    }

    if (warmup_script) {
      v8::StartupData cold = blob;
      blob = WarmUpSnapshotDataBlob(cold, warmup_script.get());
      delete[] cold.data;
    }

    delete counter_map_;

    CHECK(blob.data);
    snapshot_writer.WriteSnapshot(blob);
    delete[] blob.data;
  }
  i::FreeCurrentEmbeddedBlob();

  v8::V8::Dispose();
  v8::V8::ShutdownPlatform();
  return 0;
}
