
rule k3e9_1192d699efa10932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1192d699efa10932"
     cluster="k3e9.1192d699efa10932"
     cluster_size="1406"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma malicious"
     md5_hashes="['0194910e816d7be0f136870720c5578d','052f85bd0d2f2a9ffd73ebf46b7023f7','12a2a4328f4398a916d54a429ff6d26c']"

   strings:
      $hex_string = { 04d98254779a2a148b869621d7a9d3aa255da8f3a2255bc4d0cc37982b395702bec7e4a1489f704b2417aec2ce9b0b80c5557a0656fc8ab3e59e0979e7d8ebb4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
