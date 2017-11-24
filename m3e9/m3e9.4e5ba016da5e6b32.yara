
rule m3e9_4e5ba016da5e6b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4e5ba016da5e6b32"
     cluster="m3e9.4e5ba016da5e6b32"
     cluster_size="131"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys jorik"
     md5_hashes="['0a42561c4d8c3eb7fc4cb4075b85cd00','15929d5afde1d685bf641e4072518460','7cdc98b677988c575cab7e16d8bd0f1d']"

   strings:
      $hex_string = { 18fff401fccbe4fe6308ff1903003cf5030000006b12ffe76c18ff2e04ff404d68ff08400458ff0a19000c002d04ff0458ff1b83001b22002a4648ff5dfb3336 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
