
rule m3e7_1356dcc1cc010b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.1356dcc1cc010b32"
     cluster="m3e7.1356dcc1cc010b32"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ludbaruma regrun agentmb"
     md5_hashes="['040c2a08f697de94edd5aa3554afafc3','0d73e262c44012f5bcf097705aa5ef82','ea875956582ee482286d4a3813e132e9']"

   strings:
      $hex_string = { 83ec145356578965f4c745f8d016400033db895dfc8b7508568b06ff50048b7d0c895de857895de4e8b25900006685c0577421e8be5b00006685c00f85830000 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
