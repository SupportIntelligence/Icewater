
rule n3f8_56f29499dee30b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.56f29499dee30b10"
     cluster="n3f8.56f29499dee30b10"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="clicker androidos locker"
     md5_hashes="['6147258876f890a29fcc2e35f6ad1050b4834186','93f6da3eb0d9a6263882c58ad9c0763906466bc5','0ae356f4699e7bac2a6ad914e1c3ff746afa4a2c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.56f29499dee30b10"

   strings:
      $hex_string = { 6224313b00374c616e64726f69642f737570706f72742f76342f7769646765742f53656172636856696577436f6d706174486f6e6579636f6d6224323b00514c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
