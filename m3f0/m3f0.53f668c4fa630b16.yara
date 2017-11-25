
rule m3f0_53f668c4fa630b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.53f668c4fa630b16"
     cluster="m3f0.53f668c4fa630b16"
     cluster_size="11002"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy kryptik gepys"
     md5_hashes="['000375518ab8b5985290678c5d3a8df0','000ba9b371c36392391151bb24f9452c','005f91773474f08333904744ce851821']"

   strings:
      $hex_string = { ad56092830c1757d491d64d11e6d8640a9030470c60b364f21e36f7f82dd8e944c046e294e521cae091a4de9fb7be3461190e1fc200a9c399e129a019df265ed }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
