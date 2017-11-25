
rule n3ed_2b6bd31fc1ba50f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.2b6bd31fc1ba50f2"
     cluster="n3ed.2b6bd31fc1ba50f2"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bpchjo"
     md5_hashes="['18c26c52507f9b27d2f84c007a08f134','2213a18d89a2b3a78178a5a14e046790','6497d00878fa6d0341932d19279bddab']"

   strings:
      $hex_string = { 08403bc672f2eb2e3b3173284e8d560185d274176a0a995bf7fb8b1f80c230ff45fc88141e4e83feff75e98b45fc01072901eb0289115e5bc9c3558bec0fbec0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
