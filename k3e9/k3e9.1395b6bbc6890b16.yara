
rule k3e9_1395b6bbc6890b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395b6bbc6890b16"
     cluster="k3e9.1395b6bbc6890b16"
     cluster_size="1025"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ipamor backdoor tazbaukwkdpb"
     md5_hashes="['010fccda69331bcfad72333b8f582d79','013235c0c65c0764a0fc94fc59d571d9','04b1e0abe95e93078835dda842c4697d']"

   strings:
      $hex_string = { 10c1f8782750fea088c2126d7cf134606a1b6485ea3b556c3704110e940b809b6884aa1730b9d8c328d439f09c5f9a1592fb9f4ac97ec605221ffa573341d663 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
