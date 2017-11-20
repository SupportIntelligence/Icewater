
rule m2321_416e835aa2196b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.416e835aa2196b96"
     cluster="m2321.416e835aa2196b96"
     cluster_size="354"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['016cc0ca1726fe4cdf35d9126c142ad3','0192608cbaef662f8ca84e76e00bd658','0b5ca64c6b5b99a4736904ec66fac607']"

   strings:
      $hex_string = { 4feb4994f7477edd83fd3438c65d54abf4aff551a08a65230a9e42b930e85041d5b726a8951d328c5619d38e00914cdc1311e39d661a0b88bcd6cd396aa6beaa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
