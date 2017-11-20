
rule m3ec_51168fb99cc31b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.51168fb99cc31b32"
     cluster="m3ec.51168fb99cc31b32"
     cluster_size="203"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob pornoblocker"
     md5_hashes="['01a0975b38667d9ec3c5fa48ea8782ba','02740458867dd969dc416eee8047d6fa','19cd3b2420c826a11e79c08eb6fb0c1b']"

   strings:
      $hex_string = { 568b7510578b7d088b4f588bc103ce83e03f8945fc894f583bce7303ff475485c0764f8d0c30894df883f94072448b5d0cb9400000002bc85103c75350e8bfad }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
