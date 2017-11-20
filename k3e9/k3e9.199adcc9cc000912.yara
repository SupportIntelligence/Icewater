
rule k3e9_199adcc9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.199adcc9cc000912"
     cluster="k3e9.199adcc9cc000912"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['01b86efa34b34a49e51268ecb3114f03','38f696cc235f72a4688aa88a2d20a2fd','88ba499c6db4d258244dfe945739ecf9']"

   strings:
      $hex_string = { 1fbf4b769db61ce83cdb099817e09c37926939dcd2d73202a4c0915957e9d936ca5a8599be10661afd5af4d584611b0f376ce3a1acd45225f2a25d0305c29e19 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
