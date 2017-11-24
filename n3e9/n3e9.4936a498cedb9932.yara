
rule n3e9_4936a498cedb9932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4936a498cedb9932"
     cluster="n3e9.4936a498cedb9932"
     cluster_size="513"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['015bf8cbfc0b536453563f0dd413dd07','02e1e14a6d8d70ba4d51d852ab00e4f2','1634e3a93f6cc05afc501b4704578e3b']"

   strings:
      $hex_string = { ccb8edef0801e864a4fdff83ec2c5356578d4dc8e89d72fdffc745c86cad000133db895dfc895df08b7d0c33f63bfbc645fc017507be03400080eb02891f3bf3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
