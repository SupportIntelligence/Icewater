
rule k3e9_69d09ce939690b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69d09ce939690b12"
     cluster="k3e9.69d09ce939690b12"
     cluster_size="186"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mywebsearch toolbar malicious"
     md5_hashes="['003cc752334ac4415d35ad05c17d5e1c','008fee1ff1a608f8f6580c8f87bb81ef','1108e114ad03ce9c48f1fa479375acbf']"

   strings:
      $hex_string = { 9e281fba7f2227db873b429a5c2b0678fa830fe037809c2176ce8e386badee0aa2a8774f92c51dd5c1264708ebf6d1d29768946e2de4bff7c3bba4f082e6be24 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
