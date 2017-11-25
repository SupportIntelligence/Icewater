
rule k3e9_1b1c6898a3a10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1c6898a3a10b16"
     cluster="k3e9.1b1c6898a3a10b16"
     cluster_size="7757"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta hllp neshuta"
     md5_hashes="['00109e4b2ea046cbc3e6b63dd220e160','0019ec18ca324cc218026b70fed9508f','01027256349653168a2ff94e29bcd800']"

   strings:
      $hex_string = { 53568bf0a11492400089088bda85db7e10b8ff000000e8e5b5ffff3006464b75f05e5bc3558bec33c05568c970400064ff30648920ff0594a6400033c05a5959 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
