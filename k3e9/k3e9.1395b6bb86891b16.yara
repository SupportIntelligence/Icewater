
rule k3e9_1395b6bb86891b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395b6bb86891b16"
     cluster="k3e9.1395b6bb86891b16"
     cluster_size="167"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ipamor backdoor yzbaukwkdpb"
     md5_hashes="['01450ddc6b9666ef207de6c5fd9c81df','04b0d456a09474d79630c3983921d110','1c5a1b5a70141df5ff9a5e5688ee5e39']"

   strings:
      $hex_string = { 10c1f8782750fea088c2126d7cf134606a1b6485ea3b556c3704110e940b809b6884aa1730b9d8c328d439f09c5f9a1592fb9f4ac97ec605221ffa573341d663 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
