
rule k3e9_1395b6ba56d31916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395b6ba56d31916"
     cluster="k3e9.1395b6ba56d31916"
     cluster_size="147"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ipamor backdoor kzzbaukwkdpb"
     md5_hashes="['03b84f31374516f215d97d43acb87d66','1266dbc9eda6ea60eb599aa3bbb23ace','a27d71d67bcfd6c97e964fd237402b46']"

   strings:
      $hex_string = { 10c1f8782750fea088c2126d7cf134606a1b6485ea3b556c3704110e940b809b6884aa1730b9d8c328d439f09c5f9a1592fb9f4ac97ec605221ffa573341d663 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
