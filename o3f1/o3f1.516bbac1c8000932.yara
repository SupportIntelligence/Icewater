
rule o3f1_516bbac1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f1.516bbac1c8000932"
     cluster="o3f1.516bbac1c8000932"
     cluster_size="261"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hiddad androidos mobidash"
     md5_hashes="['022dfc3069b91e62e3ee4b5ad3046078','024fc6b84f9748a8828079fcb89d8f8b','13073319b1d571e8fe640d9d6bb42154']"

   strings:
      $hex_string = { c7020101080000014900027f10000300de0200000c00030121000000300001010800000126000b7f31000101080000010a000b7f32000101080000049a99193f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
