
rule k2321_299adcc9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.299adcc9cc000912"
     cluster="k2321.299adcc9cc000912"
     cluster_size="15"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['03f46c8fd1732706ea3a4e158819610f','0fcddbbc2cdcb836fc3ecc7f7703b4c3','fc70a98394df9bc3cbc8c95549da3a42']"

   strings:
      $hex_string = { 1fbf4b769db61ce83cdb099817e09c37926939dcd2d73202a4c0915957e9d936ca5a8599be10661afd5af4d584611b0f376ce3a1acd45225f2a25d0305c29e19 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
