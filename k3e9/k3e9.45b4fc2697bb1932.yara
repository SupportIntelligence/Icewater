
rule k3e9_45b4fc2697bb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45b4fc2697bb1932"
     cluster="k3e9.45b4fc2697bb1932"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['763266260e3c09e939b98fd9a9a86d11','78395bc5c168e18609e23fa2c0154f87','eec3f5506ccfea9c4a39e6eb184a9cef']"

   strings:
      $hex_string = { 74128a5e018ad33a5901750c4646414184d275e233c9eb051bc983d9ff85c9750c8a4f048b54241033c040880a83c7088b0f80390075b45e5b5fc20400813df8 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
