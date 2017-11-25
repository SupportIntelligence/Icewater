
rule o3e7_33335e8a5b8b1b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.33335e8a5b8b1b32"
     cluster="o3e7.33335e8a5b8b1b32"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr dlboost malicious"
     md5_hashes="['3cc4e53217389f15e47a1e9a848490bb','896600985ee97485acea62eea763528e','d92349b2196c3e323219d6a5ebb21354']"

   strings:
      $hex_string = { 004142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
