
rule k3e9_45b4fc369bbb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45b4fc369bbb1932"
     cluster="k3e9.45b4fc369bbb1932"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['080e03a3c201c2822705ce7c9a4e6fb3','1a94a2c451a5466a546e8bc434b0f0a7','f60a82fea7625b55bf5f1ea147e89e83']"

   strings:
      $hex_string = { 74128a5e018ad33a5901750c4646414184d275e233c9eb051bc983d9ff85c9750c8a4f048b54241033c040880a83c7088b0f80390075b45e5b5fc20400813df8 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
