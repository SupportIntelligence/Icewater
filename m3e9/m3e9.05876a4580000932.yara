
rule m3e9_05876a4580000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.05876a4580000932"
     cluster="m3e9.05876a4580000932"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['02f351b7ef8d3cabb8d68a3372e6b888','053ddac6e898983d9dc4356612898a57','ffa3b343b99771b6bd5910c6f4373321']"

   strings:
      $hex_string = { 56fc8955f88b55f4f6c201895d0c7574c1fa044a83fa3f76036a3f5a8b4b043b4b08754283fa20bb0000008073198bcad3eb8d4c0204f7d3215cb844fe097523 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
