
rule n26ef_4134b31a0f1646d2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26ef.4134b31a0f1646d2"
     cluster="n26ef.4134b31a0f1646d2"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="expiro malicious engine"
     md5_hashes="['737e186f4931057877b3583602d821461cb85e6e','14b2af5879e0419e26fd0a39bdd3741871ecea27','70e9057e6e27fa92bd2707413b1570e17302a994']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26ef.4134b31a0f1646d2"

   strings:
      $hex_string = { 6207f9ff33db895c2430e8970100003bc37c09395c24300f95c3eb2d488b0de3660200483bcf7421f6411c02741b807919037215488b49104c8d0577bef8ffba }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
