
rule k2321_13159250d8827916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.13159250d8827916"
     cluster="k2321.13159250d8827916"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['10c32748c93c7d7eed5221a7258ecd20','1745bbca9200091fc6ef5c986097678f','e88d9596fdfd60102c228bded2bbf325']"

   strings:
      $hex_string = { 780d276068f93bd8b292164460dfe19b2fdcfbf6f5a2958f5e583a67e5c317964ee352102d7d844b70a681a54356c718eddbe92246cd3b1d63d4b1d3f1383fbf }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
