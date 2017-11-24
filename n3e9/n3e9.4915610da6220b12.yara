
rule n3e9_4915610da6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4915610da6220b12"
     cluster="n3e9.4915610da6220b12"
     cluster_size="261"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kryptik malicious heuristic"
     md5_hashes="['002a003054bb1287c66ef0700ad4369c','012ddea2188498cacfa777152f599d7c','0c2fe3e0245719c46612c9d3de921d33']"

   strings:
      $hex_string = { 40173a2a03c15f2118967350358c82f253dc075e3042cffced15594dd953bee2367799d0caa1bb3c92ae49588b0e05661c5d608131ab267a57ddbf98eed5259d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
