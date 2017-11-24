
rule k3e9_0a68a65c0e6d48f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0a68a65c0e6d48f2"
     cluster="k3e9.0a68a65c0e6d48f2"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['1b60a86f9f1bdadd00c4562aceb0d623','1fc1e12f470a2e4d575738dfce51b4e6','fc162d82bf986f9b219a40de906d33d1']"

   strings:
      $hex_string = { 116e96bfa4c6c3c585f244482847f8a56cf1672efc5c0d1845f5826b97e7ad7da8f67033b57b16d50caeeefdbc3529362663c1cf3eff00ea045c23c23bfa512f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
