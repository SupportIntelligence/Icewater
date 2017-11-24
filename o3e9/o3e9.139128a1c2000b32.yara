
rule o3e9_139128a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.139128a1c2000b32"
     cluster="o3e9.139128a1c2000b32"
     cluster_size="413"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="itorrent loadmoney malicious"
     md5_hashes="['002edbdb0319fbea69636ede7a567392','00710a6e51980031101f1756d691cd2e','0910e1feb28a5a3b56aee9b3d3ab645c']"

   strings:
      $hex_string = { 8cbfa9476f66a1dad0b0a21c2c8694265bc924027868165db199dfc579bdaae0e7217162590c2275eede3e7f41b6f9d9148981c21af23c27c4c0a49c25531763 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
