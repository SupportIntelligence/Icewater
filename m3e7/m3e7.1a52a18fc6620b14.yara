
rule m3e7_1a52a18fc6620b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.1a52a18fc6620b14"
     cluster="m3e7.1a52a18fc6620b14"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shodi virut classic"
     md5_hashes="['0ac079d99593f3e6bf949ee8ed26317b','53cecc03ed60824877b678e1985ca1b4','f084e31e4dd0cbdec8c9d790d93db1ad']"

   strings:
      $hex_string = { 01988888119c898943af9c9c86c0acaca7cdb8b8d4d5bebeffd1b7b7ffcdafafffc19f9fffb89191ffaf8383ffb08282ff775656bf0000004800658791089dcf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
