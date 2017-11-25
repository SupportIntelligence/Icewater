
rule k2321_211b3a49c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.211b3a49c8000932"
     cluster="k2321.211b3a49c8000932"
     cluster_size="24"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol servstart heuristic"
     md5_hashes="['019aba77d0b370d0cee04f2a13a6ec79','137b483c0aefb8472a57e4018dd38c70','b5341dc77ffcd25a5599d0b59bdee8c6']"

   strings:
      $hex_string = { ee1646b56d31e3becf97866b3635a1ecf676222e0e3ec2db51e9b0921713f371a4b77790999594825c14eb5ffc5eb1981e09c3967d247a21d9a31ec0fbe89c87 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
