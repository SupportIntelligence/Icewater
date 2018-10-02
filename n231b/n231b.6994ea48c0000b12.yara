
rule n231b_6994ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231b.6994ea48c0000b12"
     cluster="n231b.6994ea48c0000b12"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['a34321c78281182d902e6f5dc1681ef9c6286799','b312a781beab3fe93031a6ac31893fb8457aad9f','6470a4ef5b43e189d07b37a0fd8a5b2e57b803d2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231b.6994ea48c0000b12"

   strings:
      $hex_string = { 657475726e20436f696e486976652e434f4e4649472e4c49425f55524c2b706174687d292c7761736d42696e6172793a73656c662e5741534d5f42494e415259 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
