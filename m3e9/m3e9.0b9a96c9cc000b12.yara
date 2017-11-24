
rule m3e9_0b9a96c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b9a96c9cc000b12"
     cluster="m3e9.0b9a96c9cc000b12"
     cluster_size="42"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['0997ad8430a33edf9b9205557dbf6393','09f8c6d2e4f72783fe572d1d1e6a1f0b','66b89268b8d5b18e08be10fa06eb4420']"

   strings:
      $hex_string = { 83477e80a6eb8afdf2851703b062a510e5112113bf69cf51d022b8caa0c9e8be97db75f69474842632c8fac4c57c5204662815670b4b0950871614405e4f2ee0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
