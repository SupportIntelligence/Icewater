
rule m3e9_3a5b955bc2220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5b955bc2220b14"
     cluster="m3e9.3a5b955bc2220b14"
     cluster_size="435"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod malicious"
     md5_hashes="['00d5f7e92db97476dfd5be9bee498469','00e4396427250327e9842e8e0ed04954','1efeebe7d12e57cace3888ccf3797b9d']"

   strings:
      $hex_string = { f736715bf20ee36b03e1924e9eefee24caabe6174448e4a60926e331209c7ac67f77b61b5fe278f9333240fd7d49a5e742a2281aa8f06fdc9891cb04052d15b8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
