
rule m2321_531213a986620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.531213a986620b12"
     cluster="m2321.531213a986620b12"
     cluster_size="22"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="linkury scriptkd toolbar"
     md5_hashes="['043d4e6d39a37611003e517b7abcadce','0779a7425c3c143fb2f5fe4b08c017a5','dba772039bf081899931c044849da3fd']"

   strings:
      $hex_string = { fef00e97aedea55345e1045a356cc47eb9bb68ff44ac6b425d73ed695c76c408ea2c0db68d19dcd9e3a4439e59140f6226994cc0ee18d2e52b8727ce1a255750 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
