
rule m3e9_029596d3c9a19932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.029596d3c9a19932"
     cluster="m3e9.029596d3c9a19932"
     cluster_size="6813"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="juched zusy ganelp"
     md5_hashes="['002dc322c7a1213c750e2c9977067eeb','0049e8b9103d96288d975e19cde5563c','0119e710eb96ac666fc9516a858c486a']"

   strings:
      $hex_string = { 510c83e2ef8b45f889500c8b4df8c7410400000000c745fc000000008b55fc8955f48b45f88b480c81e10c01000085c9752e817df880bf42007409817df8a0bf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
