
rule o26c0_5132480a9deb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.5132480a9deb1912"
     cluster="o26c0.5132480a9deb1912"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor kryptik malicious"
     md5_hashes="['ec9eb9ef5fddb69fab7ab2f9452cf5cd29d73af8','ed1d3e938755819012cea0bcaa9af0462c3a5b2f','b11a7d49a21360654925d1900cb462293f03cd97']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.5132480a9deb1912"

   strings:
      $hex_string = { 1c5e3e3f17a7d76571ce482840d09d9261fd2b5055af79e7213bbeeefbe1ba1e7e4af4d215bc9cdec580a89b77e6dd6a3910f2f88c902e1849817b0f00523ab4 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
