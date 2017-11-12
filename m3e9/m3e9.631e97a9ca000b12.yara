
rule m3e9_631e97a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631e97a9ca000b12"
     cluster="m3e9.631e97a9ca000b12"
     cluster_size="284"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['01e23f26782ca62c07634317ba70b8e0','06b8726a2bbb7fdd221582afe9e91379','2331a1880b73f6a5257fb3b97b7bc2e5']"

   strings:
      $hex_string = { d3eec8d43db62622e640a2aafdd6d97e5ff93ef41d0f52dd773efbac362abfb14f20f0430dc99156199f5df2d742c40e4e2eea063a00be72012d73aff71a68ad }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
