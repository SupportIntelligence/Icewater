
rule k3e9_1395b6bb72890916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395b6bb72890916"
     cluster="k3e9.1395b6bb72890916"
     cluster_size="970"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ipamor backdoor gyzbaukwkdpb"
     md5_hashes="['0044b5e659691cce0b17da31bd40ae98','00a4311026a9c33d2b4dac5dd673e1f9','03625367cfe3beb6d56a92718ad3edde']"

   strings:
      $hex_string = { 10c1f8782750fea088c2126d7cf134606a1b6485ea3b556c3704110e940b809b6884aa1730b9d8c328d439f09c5f9a1592fb9f4ac97ec605221ffa573341d663 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
