
rule o3e9_1659ac6a9ed36956
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1659ac6a9ed36956"
     cluster="o3e9.1659ac6a9ed36956"
     cluster_size="25"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['0bad0581302ac9dfd996302fa9dcd3de','190047740289f0c65411fb2e1b2478f8','98ab4f396e21808e1387a9488b51e550']"

   strings:
      $hex_string = { cca4dd220bcb6c8cd707129ca3b4e298ea43dfebb9128587bdd1041316e624fcf35a6945a33f80cebe5b5640b37fb895e3a0c2be29e49d005b342474c44e4626 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
