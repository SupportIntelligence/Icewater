
rule m2321_395212d3d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.395212d3d6c30912"
     cluster="m2321.395212d3d6c30912"
     cluster_size="47"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['001c6328a987d1831ad47b460638989b','0032b8e8625e647d7495818730d9cf65','5f7ffd63a467f9185500e8579a671510']"

   strings:
      $hex_string = { fd2f1762b3ce0a29debaf7ec53fc1603dda4144d313ef8263dd14cc2a2cbfbdfafbfc7c6ff6421d8973953b1106c7aaaea42b0e2842b45d67dc9c5a183eb7941 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
