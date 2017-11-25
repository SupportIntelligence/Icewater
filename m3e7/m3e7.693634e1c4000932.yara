
rule m3e7_693634e1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.693634e1c4000932"
     cluster="m3e7.693634e1c4000932"
     cluster_size="1783"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakeinst androidos trojansms"
     md5_hashes="['0008afd5736cbf7e7b579b3b63dc4f49','003050b985ed62e52bcba38f911ad240','01bf65efbe5b20448bb9c1966318876e']"

   strings:
      $hex_string = { 1625047402410115000c121a15d00308001200080115006e20400110000a150200150059e0f7003b100b00221589001a16d103760262011500290084fe1a15ca }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
