
rule m2321_3b954a1aea208916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b954a1aea208916"
     cluster="m2321.3b954a1aea208916"
     cluster_size="22"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma emotet"
     md5_hashes="['2d4ab943aae4136b219c31478b1e1552','2f312ecdb6f94149fb50b9aaee375058','d695ab6ebc480ef0b5f0517423ae63d7']"

   strings:
      $hex_string = { 9fec3ed28838dedd767483255d93b9d56b680784127332a84ea33305ac7e973504dfafbfaf0ebecc95a03aadedfbdbe21f3dfae9e14002f2349c09b130c5b88d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
