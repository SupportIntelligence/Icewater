
rule k2321_0a44a856166b48ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0a44a856166b48ba"
     cluster="k2321.0a44a856166b48ba"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['0205a387be70cfe16399ed667f3cd1c4','2b532b28473693581c982fe3594c8cc9','ca3577d3e318ff80588eb8d54a72a6e9']"

   strings:
      $hex_string = { 147ff0466fbfab35c09cd89fc705246800126466a40de5626e89b4a35c21d6b079fad1d3efd2c5778c5fa245c38d734094827a42d543597c753c3bc6600b7074 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
