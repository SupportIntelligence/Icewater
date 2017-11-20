
rule k2321_139592d0daa27916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.139592d0daa27916"
     cluster="k2321.139592d0daa27916"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tomc"
     md5_hashes="['3c47bc90993cc3e805d99e94fa94e3ca','4486d59bcaa1d13a57eb10f8562e4c5b','f2c4c4cecd485c9897c857007687f239']"

   strings:
      $hex_string = { b8e2d8ed139b944adcd377251eaf547a201207938a637cf86e252b437d090c5e37b02a0e6f80863a8feeb7bc46fd857fc656b2d6b5d5cd7e3d5cad1c2eba9d70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
