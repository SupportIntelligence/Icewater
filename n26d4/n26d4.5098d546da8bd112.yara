
rule n26d4_5098d546da8bd112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.5098d546da8bd112"
     cluster="n26d4.5098d546da8bd112"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy stantinko malicious"
     md5_hashes="['c6b83c55ad1985d8577eea0fc25b67cc94daefc6','eea4178b183c299a89adb5fddd90b6e8ce76fa2a','536e7872ed4a7ff8c69b9c2077dd8f8481a392c1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.5098d546da8bd112"

   strings:
      $hex_string = { 451f108d470850e88ef9f7ff8b5c24288bd083c40c85d274418b7a0433c985ff74388d420ceb038d49003970fc75043918740a4183c0083bcf72efeb1d4fbd01 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
