
rule k26c0_32b344e6d89f0b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c0.32b344e6d89f0b16"
     cluster="k26c0.32b344e6d89f0b16"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious paph clipspy"
     md5_hashes="['b211d5b5872b0e9e03651684719a17c091e964ca','cae7db260a023db7814161d542e4e52e956c27c7','429320d8c3e5a2f959883791e02e7e63e08a67ae']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c0.32b344e6d89f0b16"

   strings:
      $hex_string = { 0fb61380fa2a74f531c084d274d58b7c241481cf00000100eb0c8d760083c601807eff0074bd89f989f289d8e80cffffff85c075e883c42c5b5e5f5dc30fbe57 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
