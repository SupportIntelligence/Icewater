
rule k3e9_119eda99efa10932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.119eda99efa10932"
     cluster="k3e9.119eda99efa10932"
     cluster_size="426"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['01c034ec51d10dba573463436a6f6b43','023552232e9185279d6a428620e45d1c','13ac6bf3aba0a16f64ea0d7c8ffa8b81']"

   strings:
      $hex_string = { 04d98254779a2a148b869621d7a9d3aa255da8f3a2255bc4d0cc37982b395702bec7e4a1489f704b2417aec2ce9b0b80c5557a0656fc8ab3e59e0979e7d8ebb4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
