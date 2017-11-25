
rule k3e7_149158d0ca210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.149158d0ca210b12"
     cluster="k3e7.149158d0ca210b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virtob scar shyape"
     md5_hashes="['bd683c02391481c7d4c822101e15181d','bd683c02391481c7d4c822101e15181d','bd683c02391481c7d4c822101e15181d']"

   strings:
      $hex_string = { af3d2119abad156bddd0c09e2c428d9bf6cbd167c5bf30b0683c7bc9085abebcaa45e0ff1c009240415d9f741a2b573ad7a636a056e2d5a7c2c18b70fd89c87c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
