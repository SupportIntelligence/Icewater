
rule m3ed_539a529dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.539a529dc6220b12"
     cluster="m3ed.539a529dc6220b12"
     cluster_size="41"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bpchjo"
     md5_hashes="['004cd0afb9b287b72d590a207b4a989e','103e4d1595cf1681c01b20ec9aa05acc','5f54998b5fdd6a159d75c1efd1f0fd66']"

   strings:
      $hex_string = { 397de07c9233db8bf36bf6240335a0e840008b0683f8ff740b83f8fe7406804e0480eb73c646048185db75056af658eb0a8bc348f7d81bc083c0f550ff157010 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
