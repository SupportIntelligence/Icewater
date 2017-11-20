
rule m2321_1310908cca127916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1310908cca127916"
     cluster="m2321.1310908cca127916"
     cluster_size="23"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jacard filetour riskware"
     md5_hashes="['0980d860f99921ec3ec811b1ce2b7ce9','0a19fdb1a627a50b297a4aded5d50488','afa00ca57a5b9e89a42df16961709b0d']"

   strings:
      $hex_string = { 3c438be8d94f7823519a4db501070c44cbbdb2a79fcf25da81b0f44ced131b167b7d74997158a034452cd28ef6b40e55d08dfcfba6b72ef3ae7ee31f06deeed5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
