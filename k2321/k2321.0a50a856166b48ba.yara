
rule k2321_0a50a856166b48ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0a50a856166b48ba"
     cluster="k2321.0a50a856166b48ba"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['0a9598ddd76cdc98880ae3d4f25704a4','16fb40cae7dad4d942c1eb117f66b47d','a5cb11206c5bdd3894df43dbf68baa4d']"

   strings:
      $hex_string = { 147ff0466fbfab35c09cd89fc705246800126466a40de5626e89b4a35c21d6b079fad1d3efd2c5778c5fa245c38d734094827a42d543597c753c3bc6600b7074 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
