
rule k2377_2da5a5669a936b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.2da5a5669a936b96"
     cluster="k2377.2da5a5669a936b96"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script embtfc"
     md5_hashes="['1b4ec893ad88f4dca673c5632260a657','70f4ae7fa5c4263a10849afc454f6c26','eeade695b34bd168975cad71a75f2359']"

   strings:
      $hex_string = { 743d5f626c616e6b3e3c696d67207372633d272f2f636f756e7465722e796164726f2e72752f6869743f7432302e313b72222b0a65736361706528646f63756d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
