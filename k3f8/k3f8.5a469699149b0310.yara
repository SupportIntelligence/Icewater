
rule k3f8_5a469699149b0310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.5a469699149b0310"
     cluster="k3f8.5a469699149b0310"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeinst androidos fakeinstall"
     md5_hashes="['fece2428c17744cb50c53949540c0795b9929101','4194676c62833e2356ece581d1276c1734cf3d2d','02f9bc0d0c5e34cb66d69dd429588ed5643a24ff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.5a469699149b0310"

   strings:
      $hex_string = { 766974794d616e616765723b001a4c616e64726f69642f6170702f416c61726d4d616e616765723b001a4c616e64726f69642f6170702f4e6f74696669636174 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
