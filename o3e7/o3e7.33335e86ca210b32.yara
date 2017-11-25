
rule o3e7_33335e86ca210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.33335e86ca210b32"
     cluster="o3e7.33335e86ca210b32"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr malicious dlboost"
     md5_hashes="['1452c169e9bd577b6fd7197bffaed3d7','a4c594292ce97accce6daf51cc244ddc','a4c594292ce97accce6daf51cc244ddc']"

   strings:
      $hex_string = { 006162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758595a313233343536373839302d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
